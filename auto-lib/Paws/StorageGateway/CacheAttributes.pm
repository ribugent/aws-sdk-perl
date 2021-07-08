# Generated by default/object.tt
package Paws::StorageGateway::CacheAttributes;
  use Moose;
  has CacheStaleTimeoutInSeconds => (is => 'ro', isa => 'Int');

1;

### main pod documentation begin ###

=head1 NAME

Paws::StorageGateway::CacheAttributes

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::StorageGateway::CacheAttributes object:

  $service_obj->Method(Att1 => { CacheStaleTimeoutInSeconds => $value, ..., CacheStaleTimeoutInSeconds => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::StorageGateway::CacheAttributes object:

  $result = $service_obj->Method(...);
  $result->Att1->CacheStaleTimeoutInSeconds

=head1 DESCRIPTION

The refresh cache information for the file share.

=head1 ATTRIBUTES


=head2 CacheStaleTimeoutInSeconds => Int

Refreshes a file share's cache by using Time To Live (TTL). TTL is the
length of time since the last refresh after which access to the
directory would cause the file gateway to first refresh that
directory's contents from the Amazon S3 bucket or Amazon FSx file
system. The TTL duration is in seconds.

Valid Values: 300 to 2,592,000 seconds (5 minutes to 30 days)



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::StorageGateway>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

