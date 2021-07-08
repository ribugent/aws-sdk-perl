# Generated by default/object.tt
package Paws::IoTAnalytics::LateDataRuleConfiguration;
  use Moose;
  has DeltaTimeSessionWindowConfiguration => (is => 'ro', isa => 'Paws::IoTAnalytics::DeltaTimeSessionWindowConfiguration', request_name => 'deltaTimeSessionWindowConfiguration', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoTAnalytics::LateDataRuleConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoTAnalytics::LateDataRuleConfiguration object:

  $service_obj->Method(Att1 => { DeltaTimeSessionWindowConfiguration => $value, ..., DeltaTimeSessionWindowConfiguration => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoTAnalytics::LateDataRuleConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->DeltaTimeSessionWindowConfiguration

=head1 DESCRIPTION

The information needed to configure a delta time session window.

=head1 ATTRIBUTES


=head2 DeltaTimeSessionWindowConfiguration => L<Paws::IoTAnalytics::DeltaTimeSessionWindowConfiguration>

The information needed to configure a delta time session window.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoTAnalytics>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

